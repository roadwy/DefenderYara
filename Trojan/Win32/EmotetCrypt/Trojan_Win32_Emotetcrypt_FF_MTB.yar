
rule Trojan_Win32_Emotetcrypt_FF_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b ea 03 eb 03 6c 24 90 01 01 0f b6 14 2e 03 c2 33 d2 f7 35 90 01 04 8d 04 49 b9 03 00 00 00 2b c8 0f af cb 8d 04 7f 03 d1 2b d0 0f b6 0c 32 8b 44 24 90 01 01 30 08 90 00 } //1
		$a_81_1 = {4c 57 30 3c 48 3c 72 4a 79 21 28 58 53 55 70 79 57 37 6c 70 6b 46 23 61 56 23 56 41 32 4c 25 5a 6b 3c 6c 44 52 33 3c 42 3e 72 61 49 3f } //1 LW0<H<rJy!(XSUpyW7lpkF#aV#VA2L%Zk<lDR3<B>raI?
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}