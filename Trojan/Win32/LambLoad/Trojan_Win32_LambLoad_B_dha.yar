
rule Trojan_Win32_LambLoad_B_dha{
	meta:
		description = "Trojan:Win32/LambLoad.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 34 32 59 4a 79 e3 80 3e 4d 75 12 80 7e 01 5a 75 0c } //100
	condition:
		((#a_01_0  & 1)*100) >=100
 
}