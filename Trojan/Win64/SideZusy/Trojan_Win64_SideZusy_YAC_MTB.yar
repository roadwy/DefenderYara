
rule Trojan_Win64_SideZusy_YAC_MTB{
	meta:
		description = "Trojan:Win64/SideZusy.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {c8 80 00 00 48 81 ec } //1
		$a_03_1 = {32 c3 48 8d 3f 48 8d 3f 90 13 02 c3 48 8d 3f 32 c3 e9 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}