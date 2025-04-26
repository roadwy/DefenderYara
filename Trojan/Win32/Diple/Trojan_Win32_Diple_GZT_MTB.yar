
rule Trojan_Win32_Diple_GZT_MTB{
	meta:
		description = "Trojan:Win32/Diple.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 56 57 68 00 82 40 00 33 f6 56 56 ff 15 } //10
		$a_01_1 = {69 4b 6a 68 7a 5a 72 68 76 55 29 79 71 4f 6b 6d 32 43 6b 6d 35 5a 76 71 75 52 65 } //1 iKjhzZrhvU)yqOkm2Ckm5ZvquRe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}