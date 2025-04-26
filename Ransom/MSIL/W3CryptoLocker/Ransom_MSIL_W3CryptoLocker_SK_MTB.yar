
rule Ransom_MSIL_W3CryptoLocker_SK_MTB{
	meta:
		description = "Ransom:MSIL/W3CryptoLocker.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 65 6e 74 69 6f 6e 21 } //5 Attention!
		$a_01_1 = {57 33 43 52 59 50 54 4f 20 4c 4f 43 4b 45 52 } //5 W3CRYPTO LOCKER
		$a_01_2 = {52 00 65 00 61 00 64 00 5f 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 Read_Me.txt
		$a_01_3 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //1 select * from Win32_ShadowCopy
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}