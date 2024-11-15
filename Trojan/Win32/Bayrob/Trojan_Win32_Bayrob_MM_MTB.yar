
rule Trojan_Win32_Bayrob_MM_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f bf c8 89 4d fc 57 56 db 45 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}