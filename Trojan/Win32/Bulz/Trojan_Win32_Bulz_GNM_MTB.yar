
rule Trojan_Win32_Bulz_GNM_MTB{
	meta:
		description = "Trojan:Win32/Bulz.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 c0 00 fb fd 23 54 ff 2a 46 34 ff fc f6 c0 fb 32 04 00 58 ff 54 ff f3 53 21 eb f3 e3 12 } //10
		$a_80_1 = {65 38 69 74 2e 6e 65 74 2f 74 75 69 67 75 61 6e 67 2f 71 75 64 61 6f } //e8it.net/tuiguang/qudao  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}