
rule Trojan_Win32_FormBook_AFK_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 5e 02 88 4e 02 88 5c 02 02 0f b6 4e 02 8b 55 0c 02 cb 0f b6 c9 0f b6 4c 01 02 32 cf } //00 00 
	condition:
		any of ($a_*)
 
}