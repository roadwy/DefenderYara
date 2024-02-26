
rule Trojan_Win32_LummaStealer_CCCZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 f0 8b c3 33 c0 33 db 8b f6 8b db 8b d8 8b c3 f6 2f 47 e2 } //00 00 
	condition:
		any of ($a_*)
 
}