
rule Trojan_Win32_LummaStealer_CCCV_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 3c 32 0f b6 db 31 fb 33 04 9d 90 01 04 46 89 c3 39 f1 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}