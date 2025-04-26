
rule Backdoor_Win64_RomCom_B{
	meta:
		description = "Backdoor:Win64/RomCom.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 03 48 8b [0-06] 48 d3 ea 48 8b ca 0f b6 c9 33 c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}