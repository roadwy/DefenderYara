
rule Trojan_Win64_Shellcoderunner_DA_MTB{
	meta:
		description = "Trojan:Win64/Shellcoderunner.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d ac 24 00 02 00 00 48 8d 15 ?? ?? ?? ?? 52 48 8d 15 ?? ?? ?? ?? 52 c3 90 09 07 00 48 81 ec } //1
		$a_03_1 = {48 8d ac 24 00 02 00 00 48 8d 05 ?? ?? ?? ?? 50 55 48 89 e5 48 81 ec 90 09 07 00 48 81 ec } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}