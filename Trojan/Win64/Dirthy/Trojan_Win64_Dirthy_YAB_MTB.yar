
rule Trojan_Win64_Dirthy_YAB_MTB{
	meta:
		description = "Trojan:Win64/Dirthy.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2d 43 6f 6d 6d 61 6e 64 43 6c 65 61 72 2d 52 65 63 79 63 6c 65 42 69 6e 20 2d 46 6f 72 63 65 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //10 powershell.exe-CommandClear-RecycleBin -Force -ErrorAction SilentlyContinue
		$a_01_1 = {55 6e 72 65 67 69 73 74 65 72 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 20 2d 54 61 73 6b 4e 61 6d 65 20 24 74 61 73 6b 2e 54 61 73 6b 4e 61 6d 65 20 2d 43 6f 6e 66 69 72 6d } //1 Unregister-ScheduledTask -TaskName $task.TaskName -Confirm
		$a_01_2 = {5f 5f 69 6d 70 5f 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 __imp_CreateToolhelp32Snapshot
		$a_01_3 = {63 6f 64 65 2f 72 75 73 74 63 2f 33 66 35 66 64 38 64 64 34 31 31 35 33 62 63 35 66 64 63 61 39 34 32 37 65 39 65 30 35 62 65 32 63 37 36 37 62 61 32 33 5c 6c 69 62 72 61 72 79 5c 73 74 64 5c 73 72 63 5c 69 6f 5c 65 72 72 6f 72 5c 72 65 70 72 5f 62 69 74 70 61 63 6b 65 64 2e 72 73 } //1 code/rustc/3f5fd8dd41153bc5fdca9427e9e05be2c767ba23\library\std\src\io\error\repr_bitpacked.rs
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}