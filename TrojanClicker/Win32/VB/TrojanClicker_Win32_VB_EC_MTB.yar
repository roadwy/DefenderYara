
rule TrojanClicker_Win32_VB_EC_MTB{
	meta:
		description = "TrojanClicker:Win32/VB.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {56 42 2e 43 6c 69 70 62 6f 61 72 64 } //1 VB.Clipboard
		$a_81_1 = {2f 74 75 69 67 75 61 6e 67 2f 71 75 64 61 6f } //1 /tuiguang/qudao
		$a_81_2 = {5c 53 6e 61 70 2e 76 62 70 } //1 \Snap.vbp
		$a_81_3 = {74 61 73 6b 6d 67 72 } //1 taskmgr
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}