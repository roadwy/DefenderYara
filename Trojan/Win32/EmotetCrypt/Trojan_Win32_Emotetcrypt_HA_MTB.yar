
rule Trojan_Win32_Emotetcrypt_HA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 1a 03 c2 99 bd ?? ?? ?? ?? f7 fd a1 ?? ?? ?? ?? 8d 44 00 ?? 0f af 05 ?? ?? ?? ?? 03 d0 8d 0c 4a 8d 14 f5 ?? ?? ?? ?? 8b 44 24 ?? 2b d6 2b ca 0f b6 0c 19 30 08 83 c7 ?? 3b 7c 24 ?? 89 7c 24 ?? 0f 82 } //1
		$a_81_1 = {42 57 39 43 67 52 42 24 3c 4a 43 50 54 24 2a 2a 5a 50 57 33 4b 23 23 59 77 26 28 6e 65 43 53 78 42 56 44 35 3f 26 21 47 4d 38 52 47 26 6b 31 4d } //1 BW9CgRB$<JCPT$**ZPW3K##Yw&(neCSxBVD5?&!GM8RG&k1M
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}