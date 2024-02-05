
rule Trojan_Win32_Midie_SIBQ_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 10 04 0b 0f 28 cb 66 0f fc c8 66 0f f8 ca 66 0f f8 cc 66 0f ef cd 66 0f ef ce 66 0f ef cf 66 0f ef 0d 90 01 04 66 0f fc ca 66 0f fc 0d 90 01 04 66 0f ef 0d 90 01 04 66 0f f8 0d 90 01 04 0f 11 0c 0b 0f 10 44 0b 10 66 0f fc c3 66 0f f8 c2 66 0f f8 c4 66 0f ef c5 66 0f ef c6 66 0f ef c7 66 0f ef 05 90 1b 00 66 0f fc c2 66 0f fc 05 90 1b 01 66 0f ef 05 90 1b 02 66 0f f8 05 90 1b 03 0f 11 44 0b 10 83 c1 20 3b ca 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}