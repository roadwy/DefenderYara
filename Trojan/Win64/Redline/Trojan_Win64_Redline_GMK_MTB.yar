
rule Trojan_Win64_Redline_GMK_MTB{
	meta:
		description = "Trojan:Win64/Redline.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {34 40 00 ff 34 40 ?? ?? bc 97 44 7a f1 bf 58 3a b0 f6 20 6b b0 fe 80 56 b0 5b 94 } //10
		$a_01_1 = {58 62 6a 73 34 32 68 73 34 7a } //1 Xbjs42hs4z
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}