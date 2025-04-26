
rule Ransom_Win64_Knight_ZC_MTB{
	meta:
		description = "Ransom:Win64/Knight.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2b 49 6e 66 2d 49 6e 66 2e 62 61 74 2e 63 6d 64 2e 63 6f 6d 2e 65 78 65 2e 70 6e 67 } //1 +Inf-Inf.bat.cmd.com.exe.png
		$a_01_1 = {6c 6f 63 61 6c 2e 6f 6e 69 6f 6e 2f 71 75 69 65 74 } //1 local.onion/quiet
		$a_01_2 = {22 6b 69 6c 6c 5f 73 65 72 76 69 63 65 73 5c 22 22 3b 20 53 65 74 57 61 6c 6c 70 61 70 65 72 } //1 "kill_services\""; SetWallpaper
		$a_01_3 = {22 6e 65 74 5f 73 70 72 65 61 64 5c 22 22 3b 20 53 65 6c 66 44 65 6c 65 74 65 } //1 "net_spread\""; SelfDelete
		$a_01_4 = {61 76 78 35 31 32 63 68 61 6e 3c 2d 64 6f 6d 61 69 6e 65 6e 61 62 6c 65 65 78 65 63 } //1 avx512chan<-domainenableexec
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}