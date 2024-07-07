
rule Trojan_Win32_Emotetcrypt_FD_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d1 03 15 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 2b d1 2b 15 90 01 04 2b 15 90 01 04 2b 15 90 01 04 03 15 90 01 04 2b 15 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 03 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2 90 00 } //1
		$a_81_1 = {69 51 75 69 77 66 25 42 59 25 68 36 49 54 53 50 6f 28 40 63 4c 62 48 29 79 50 30 62 74 73 7a 2b 58 50 70 4a 53 4a 5a 21 5e 50 63 23 79 67 73 55 3e 42 56 66 3e 6d 77 42 70 48 51 2b 68 78 78 44 35 54 52 59 65 58 32 3e 69 39 62 37 78 26 48 4a 77 52 23 } //1 iQuiwf%BY%h6ITSPo(@cLbH)yP0btsz+XPpJSJZ!^Pc#ygsU>BVf>mwBpHQ+hxxD5TRYeX2>i9b7x&HJwR#
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}