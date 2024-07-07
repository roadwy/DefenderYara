
rule Trojan_Win32_Stealer_RPS_MTB{
	meta:
		description = "Trojan:Win32/Stealer.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 34 1f 80 90 02 20 5a 90 02 20 e8 90 02 30 89 14 18 90 02 30 85 db 75 90 02 30 ff e0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}