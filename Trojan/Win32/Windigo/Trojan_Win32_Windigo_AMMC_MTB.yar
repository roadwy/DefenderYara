
rule Trojan_Win32_Windigo_AMMC_MTB{
	meta:
		description = "Trojan:Win32/Windigo.AMMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {70 3a 2f 2f 65 78 70 65 72 74 63 61 72 72 69 61 67 65 2e 73 69 74 65 2f 61 72 72 61 2e 70 68 70 } //p://expertcarriage.site/arra.php  2
		$a_80_1 = {70 73 3a 2f 2f 70 6c 61 6e 65 73 67 6f 6c 64 2e 73 69 74 65 2f 74 72 61 63 6b 65 72 2f 74 68 61 6e 6b 5f 79 6f 75 2e 70 68 70 } //ps://planesgold.site/tracker/thank_you.php  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}