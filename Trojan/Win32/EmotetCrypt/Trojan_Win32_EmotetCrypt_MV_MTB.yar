
rule Trojan_Win32_EmotetCrypt_MV_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f1 8b 45 08 [0-05] 32 [0-03] 47 3b [0-03] 88 [0-05] 90 18 8b [0-05] ff [0-03] 8d [0-03] e8 [0-04] 59 33 [0-03] 8b [0-03] 8b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}