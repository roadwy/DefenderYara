
rule TrojanDropper_Win32_CryptInject_DH_MTB{
	meta:
		description = "TrojanDropper:Win32/CryptInject.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 0e 32 55 18 88 16 46 ff 4d 14 75 f2 } //2
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //2 VirtualAlloc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}