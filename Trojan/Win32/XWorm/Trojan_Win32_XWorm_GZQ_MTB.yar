
rule Trojan_Win32_XWorm_GZQ_MTB{
	meta:
		description = "Trojan:Win32/XWorm.GZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 85 ac fe ff ff 4c c6 85 ad fe ff ff 6f c6 85 ae fe ff ff 61 c6 85 af fe ff ff 64 c6 85 b0 fe ff ff 4c c6 85 b1 fe ff ff 69 c6 85 b2 fe ff ff 62 c6 85 b3 fe ff ff 72 c6 85 b4 fe ff ff 61 c6 85 b5 fe ff ff 72 c6 85 b6 fe ff ff 79 c6 85 b7 fe ff ff 57 } //5
		$a_01_1 = {5a b8 6b 00 00 00 66 89 85 50 fd ff ff b9 65 00 00 00 66 89 8d 52 fd ff ff ba 72 00 00 00 66 89 95 54 fd ff ff b8 6e 00 00 00 66 89 85 56 fd ff ff b9 65 00 00 00 66 89 8d 58 fd ff ff ba 6c 00 00 00 66 89 95 5a fd ff ff b8 33 00 00 00 66 89 85 5c fd ff ff b9 32 00 00 00 66 89 8d 5e fd ff ff ba 2e 00 00 00 66 89 95 60 fd ff ff b8 64 00 00 00 66 89 85 62 fd ff ff b9 6c 00 00 00 66 89 8d 64 fd ff ff ba 6c 00 00 00 66 89 95 66 fd ff ff 33 c0 66 89 85 68 fd ff ff c7 85 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}