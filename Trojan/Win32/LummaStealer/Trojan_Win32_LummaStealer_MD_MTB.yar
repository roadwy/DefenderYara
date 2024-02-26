
rule Trojan_Win32_LummaStealer_MD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {22 eb f5 44 22 74 06 75 04 94 16 31 99 c7 44 24 fc 30 00 00 00 83 ec 04 75 } //02 00 
		$a_01_1 = {3d 3f d5 0e 82 43 c3 18 ea 3f c8 01 d2 2a b2 2a 72 03 cd 39 43 4c 36 28 6b b9 af 45 6c f1 cd 3f } //00 00 
	condition:
		any of ($a_*)
 
}