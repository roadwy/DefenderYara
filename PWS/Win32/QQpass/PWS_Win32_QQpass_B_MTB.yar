
rule PWS_Win32_QQpass_B_MTB{
	meta:
		description = "PWS:Win32/QQpass.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6d 65 74 48 69 74 4d 6f 76 65 } //1 CometHitMove
		$a_00_1 = {43 72 61 63 6b 4d 65 } //1 CrackMe
		$a_02_2 = {2e 74 69 65 74 75 6b 75 2e 63 6f 6d 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 70 6e 67 } //1
		$a_00_3 = {70 61 74 68 2e 69 6e 69 } //1 path.ini
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}