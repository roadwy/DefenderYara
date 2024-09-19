
rule Trojan_Win32_OffLoader_ADP_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ADP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 00 6f 00 74 00 69 00 6f 00 6e 00 73 00 70 00 61 00 63 00 65 00 2e 00 73 00 70 00 61 00 63 00 65 00 2f 00 6b 00 6c 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 } //3 motionspace.space/klo.php?
		$a_01_1 = {2f 00 6e 00 6f 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //1 /nocookies
		$a_01_2 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}