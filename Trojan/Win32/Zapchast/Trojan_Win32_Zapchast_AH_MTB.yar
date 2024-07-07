
rule Trojan_Win32_Zapchast_AH_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 e0 1f 6a 20 59 2b c8 8b 45 08 d3 c8 } //5
		$a_01_1 = {58 59 5a 58 7c 5a 54 58 54 7c 58 59 5a 58 7c 5a 54 58 54 7c 58 59 5a 58 7c 5a 54 58 54 7c 58 59 5a 58 7c 5a 54 58 54 7c 58 59 5a 58 } //5 XYZX|ZTXT|XYZX|ZTXT|XYZX|ZTXT|XYZX|ZTXT|XYZX
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}