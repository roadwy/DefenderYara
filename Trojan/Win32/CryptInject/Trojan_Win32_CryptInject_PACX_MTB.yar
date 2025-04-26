
rule Trojan_Win32_CryptInject_PACX_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PACX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 2f 4e f6 c5 0e 0f b3 ea 0f ac ea 52 0f ce 86 d6 0f b3 ce 0f c0 f2 8a f4 b6 26 f9 0f ad ea 0f ca 84 c1 8a d0 0f c0 d6 b2 82 f6 c5 06 f6 da eb c6 } //1
		$a_01_1 = {74 40 8a d0 0f ba f2 4a 0f af d5 0f ad ea 0f af d5 b6 26 84 c1 c0 ca ea 2a f4 80 ee ee fe ca 86 f2 0f bd d5 0f bd d5 0f bd d5 b2 82 0f be f4 d2 ee 84 e5 c0 ee 36 f6 da 0a d0 8a d0 f6 da 2a f4 eb b5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}