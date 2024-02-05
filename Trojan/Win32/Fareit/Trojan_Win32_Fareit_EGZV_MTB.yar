
rule Trojan_Win32_Fareit_EGZV_MTB{
	meta:
		description = "Trojan:Win32/Fareit.EGZV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 cf f8 ef ed dd } //00 00 
	condition:
		any of ($a_*)
 
}