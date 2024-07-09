
rule Trojan_Win32_Emotetcrypt_ID_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.ID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 0f b6 04 02 8b 55 0c 0f b6 0c 0a 33 c8 8b 55 f4 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 45 0c 88 0c 10 e9 } //1
		$a_81_1 = {54 4e 5e 39 42 21 32 34 55 55 4a 4a 4e 6d 37 65 31 70 56 59 77 63 4c 68 31 32 66 66 5a 39 69 4b 41 79 2a 54 66 2b 37 48 35 5f 5e 39 36 47 61 63 56 } //1 TN^9B!24UUJJNm7e1pVYwcLh12ffZ9iKAy*Tf+7H5_^96GacV
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}