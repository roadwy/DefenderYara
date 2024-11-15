
rule Trojan_Win32_Bayrob_ML_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.ML!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 02 8b df 3b f3 75 d1 5f 5d 8b c6 5e 5b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}