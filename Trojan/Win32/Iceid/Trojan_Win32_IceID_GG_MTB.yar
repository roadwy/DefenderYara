
rule Trojan_Win32_IceID_GG_MTB{
	meta:
		description = "Trojan:Win32/IceID.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b fa 8d 84 3d [0-04] 8a 10 88 16 88 18 0f b6 [0-02] 0f b6 [0-02] 03 c2 99 8b f1 f7 fe 8b 85 [0-04] 8a 94 [0-05] 30 10 40 83 7d [0-02] 00 89 85 [0-04] 75 90 0a 88 00 ff 4d [0-02] 40 33 d2 } //1
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}