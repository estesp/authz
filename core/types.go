package core

var (
	ActionContainerArchive        string = "container_archive"
	ActionContainerArchiveExtract string = "container_archive_extract"
	ActionContainerArchiveHead    string = "container_archive_head"
	ActionContainerAttach         string = "container_attach"
	ActionContainerAttachWs       string = "container_attachws"
	ActionContainerChanges        string = "container_changes"
	ActionContainerCommit         string = "container_commit"
	ActionContainerCopyFiles      string = "container_copyfiles"
	ActionContainerCreate         string = "container_create"
	ActionContainerDelete         string = "container_delete"
	ActionContainerExecCreate     string = "container_exec_create"
	ActionContainerExecInspect    string = "container_exec_inspect"
	ActionContainerExecStart      string = "container_exec_start"
	ActionContainerExport         string = "container_export"
	ActionContainerInspect        string = "container_inspect"
	ActionContainerKill           string = "container_kill"
	ActionContainerList           string = "container_list"
	ActionContainerLogs           string = "container_logs"
	ActionContainerPause          string = "container_pause"
	ActionContainerRename         string = "container_rename"
	ActionContainerResize         string = "container_resize"
	ActionContainerRestart        string = "container_restart"
	ActionContainerStart          string = "container_start"
	ActionContainerStats          string = "container_stats"
	ActionContainerStop           string = "container_stop"
	ActionContainerTop            string = "container_top"
	ActionContainerUnpause        string = "container_unpause"
	ActionContainerWait           string = "container_wait"
	ActionDockerCheckAuth         string = "docker_auth"
	ActionDockerEvents            string = "docker_events"
	ActionDockerInfo              string = "docker_info"
	ActionDockerPing              string = "docker_ping"
	ActionDockerVersion           string = "docker_version"
	ActionImageArchive            string = "images_archive"
	ActionImageBuild              string = "image_build"
	ActionImageCreate             string = "image_create"
	ActionImageDelete             string = "image_delete"
	ActionImageHistory            string = "image_history"
	ActionImageInspect            string = "image_inspect"
	ActionImageList               string = "image_list"
	ActionImageLoad               string = "images_load"
	ActionImagePush               string = "image_push"
	ActionImagesSearch            string = "images_search"
	ActionImageTag                string = "image_tag"
	ActionNone                    string = ""
)