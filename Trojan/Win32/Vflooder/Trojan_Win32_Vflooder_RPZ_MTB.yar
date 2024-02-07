
rule Trojan_Win32_Vflooder_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Vflooder.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 00 74 00 62 00 6f 00 73 00 73 00 2e 00 79 00 6f 00 6c 00 6f 00 78 00 2e 00 6e 00 65 00 74 00 } //01 00  vtboss.yolox.net
		$a_01_1 = {2f 00 6d 00 64 00 35 00 2e 00 70 00 68 00 70 00 } //01 00  /md5.php
		$a_01_2 = {43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 62 69 6e 61 72 79 } //01 00  Content-Transfer-Encoding: binary
		$a_01_3 = {2e 72 6f 70 66 } //00 00  .ropf
	condition:
		any of ($a_*)
 
}