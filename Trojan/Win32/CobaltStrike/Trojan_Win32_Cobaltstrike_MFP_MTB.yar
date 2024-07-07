
rule Trojan_Win32_Cobaltstrike_MFP_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 c0 33 c9 0f a2 44 8b c1 45 33 db 44 8b cb 41 81 f0 6e 74 65 6c 41 81 f1 47 65 6e 75 44 8b d2 8b f0 33 c9 41 8d 90 01 02 45 0b c8 0f a2 41 81 f2 90 00 } //5
		$a_02_1 = {66 0f 6e c3 8b fb f3 0f e6 c0 be 02 90 01 03 e8 90 01 04 66 0f 2f 05 90 01 04 72 90 01 01 8b c7 99 f7 fe 85 d2 0f 45 c7 ff c6 8b f8 66 0f 6e c0 f3 0f e6 c0 66 0f 6e f6 f3 0f e6 f6 e8 66 66 01 00 66 0f 2f c6 73 90 01 01 ff c3 81 fb 7f 84 1e 00 7c 90 00 } //5
		$a_00_2 = {0f 10 03 0f 11 01 0f 10 4b 10 0f 11 49 10 0f 10 43 20 0f 11 41 20 0f 10 4b 30 0f 11 49 30 0f 10 43 40 0f 11 41 40 0f 10 4b 50 0f 11 49 50 0f 10 43 60 0f 11 41 60 48 03 cd 0f 10 4b 70 48 03 dd 0f 11 49 f0 48 83 ef 01 75 } //5
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5+(#a_00_2  & 1)*5) >=10
 
}