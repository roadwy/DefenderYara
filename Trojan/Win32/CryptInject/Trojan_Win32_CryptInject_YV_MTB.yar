
rule Trojan_Win32_CryptInject_YV_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 8b 90 01 02 25 ff 00 00 00 0f b6 c8 51 e8 90 01 04 83 c4 04 8b 45 08 8b 55 0c b1 90 01 01 e8 90 01 04 25 ff 00 00 00 0f b6 d0 52 90 00 } //01 00 
		$a_02_1 = {55 8b ec a1 90 01 03 00 c1 e8 90 01 01 25 ff ff ff 00 0f b6 4d 08 33 90 01 04 00 81 e1 ff 00 00 00 33 04 90 01 04 00 a3 90 01 03 00 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}