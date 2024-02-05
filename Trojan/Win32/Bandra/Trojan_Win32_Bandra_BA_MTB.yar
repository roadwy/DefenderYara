
rule Trojan_Win32_Bandra_BA_MTB{
	meta:
		description = "Trojan:Win32/Bandra.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d0 83 f2 01 0f af d0 8b 45 f4 c1 ea 08 32 14 30 88 55 fc e8 90 02 04 8b 55 f4 ff 45 f4 8a 45 fc 88 04 32 39 5d f4 72 90 00 } //01 00 
		$a_01_1 = {6b 6f 79 75 2e 73 70 61 63 65 2f 40 72 6f 6e 78 69 6b 31 32 33 } //00 00 
	condition:
		any of ($a_*)
 
}