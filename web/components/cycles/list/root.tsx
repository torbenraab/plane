import { FC } from "react";
import { observer } from "mobx-react-lite";
import { ChevronRight } from "lucide-react";
import { Disclosure } from "@headlessui/react";
// components
import { ListLayout } from "@/components/core/list";
import { CyclePeekOverview, CyclesListMap } from "@/components/cycles";
// helpers
import { cn } from "@/helpers/common.helper";

export interface ICyclesList {
  completedCycleIds: string[];
  cycleIds: string[];
  workspaceSlug: string;
  projectId: string;
  isArchived?: boolean;
}

export const CyclesList: FC<ICyclesList> = observer((props) => {
  const { completedCycleIds, cycleIds, workspaceSlug, projectId, isArchived = false } = props;

  return (
    <div className="h-full overflow-y-auto">
      <div className="flex h-full w-full justify-between">
        <ListLayout>
          <CyclesListMap
            cycleIds={cycleIds}
            projectId={projectId}
            workspaceSlug={workspaceSlug}
          />
          {completedCycleIds.length !== 0 && (
            <Disclosure as="div" className="py-8 pl-3 space-y-4">
              <Disclosure.Button className="bg-custom-background-80 font-semibold text-sm py-1 px-2 rounded ml-5 flex items-center gap-1">
                {({ open }) => (
                  <>
                    Completed cycles ({completedCycleIds.length})
                    <ChevronRight
                      className={cn("h-3 w-3 transition-all", {
                        "rotate-90": open,
                      })}
                    />
                  </>
                )}
              </Disclosure.Button>
              <Disclosure.Panel>
                <CyclesListMap cycleIds={completedCycleIds} projectId={projectId} workspaceSlug={workspaceSlug} />
              </Disclosure.Panel>
            </Disclosure>
          )}
        </ListLayout>
        <CyclePeekOverview projectId={projectId} workspaceSlug={workspaceSlug} isArchived={isArchived} />
      </div>
    </div>
  );
});
