
rule VirTool_Win64_Mimirust_A_MTB{
	meta:
		description = "VirTool:Win64/Mimirust.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 69 6d 69 52 75 73 74 } //1 mimiRust
		$a_01_1 = {6c 73 61 73 73 2e 65 78 65 } //1 lsass.exe
		$a_01_2 = {64 75 6d 70 2d 63 72 65 64 65 6e 74 69 61 6c 73 } //1 dump-credentials
		$a_01_3 = {64 75 6d 70 2d 68 61 73 68 65 73 } //1 dump-hashes
		$a_01_4 = {77 64 69 67 65 73 74 5c 6d 6f 64 2e 72 73 } //1 wdigest\mod.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}