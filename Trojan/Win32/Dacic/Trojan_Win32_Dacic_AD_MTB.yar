
rule Trojan_Win32_Dacic_AD_MTB{
	meta:
		description = "Trojan:Win32/Dacic.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a c1 8a ca c0 e9 04 c0 e3 02 83 c4 20 0a cb 8a 5c 24 1c 46 47 80 fb 40 75 ?? 8b 44 24 24 32 db 48 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}