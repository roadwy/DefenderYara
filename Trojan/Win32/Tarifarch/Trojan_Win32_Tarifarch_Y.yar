
rule Trojan_Win32_Tarifarch_Y{
	meta:
		description = "Trojan:Win32/Tarifarch.Y,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 5a 69 70 20 32 30 31 31 } //1 WinZip 2011
		$a_01_1 = {2f 00 73 00 65 00 61 00 72 00 63 00 68 00 3f 00 69 00 64 00 3d 00 } //1 /search?id=
		$a_01_2 = {6c 53 77 69 74 63 68 54 6f 4e 6f 72 6d 61 6c 53 6d 73 4d 6f 64 65 } //1 lSwitchToNormalSmsMode
		$a_01_3 = {6f 6e 53 75 62 73 63 72 69 70 74 69 6f 6e 4e 75 6d 62 65 72 43 68 61 6e 67 65 } //1 onSubscriptionNumberChange
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}