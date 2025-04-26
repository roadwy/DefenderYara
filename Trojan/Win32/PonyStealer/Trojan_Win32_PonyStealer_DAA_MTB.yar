
rule Trojan_Win32_PonyStealer_DAA_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 0c 30 8a 09 80 f1 63 8d 1c 30 88 0b 90 90 40 4a 75 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}