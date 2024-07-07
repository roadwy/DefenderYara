
rule TrojanDownloader_Win32_Agent_EF_MTB{
	meta:
		description = "TrojanDownloader:Win32/Agent.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 61 73 62 69 74 2e 63 6e 2f 7a 69 70 61 63 6b 2f 66 75 6c 6c } //1 //asbit.cn/zipack/full
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 6d 64 69 72 20 2f 73 20 2f 71 } //1 cmd.exe /c rmdir /s /q
		$a_01_2 = {46 61 73 74 20 44 65 73 6b 74 6f 70 } //1 Fast Desktop
		$a_01_3 = {51 6b 6b 62 61 6c } //1 Qkkbal
		$a_01_4 = {5f 5f 65 6e 74 72 79 40 38 } //1 __entry@8
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}