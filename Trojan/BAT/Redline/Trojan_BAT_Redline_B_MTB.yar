
rule Trojan_BAT_Redline_B_MTB{
	meta:
		description = "Trojan:BAT/Redline.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 06 1f 3c 58 16 52 06 1f 1c 58 } //1
		$a_81_1 = {66 73 64 68 6a 69 75 66 73 64 } //1 fsdhjiufsd
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}