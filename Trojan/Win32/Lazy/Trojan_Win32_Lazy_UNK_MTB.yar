
rule Trojan_Win32_Lazy_UNK_MTB{
	meta:
		description = "Trojan:Win32/Lazy.UNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {e9 58 b7 0b 00 cc cc cc cc cc 68 10 ec 45 00 64 ff 35 } //00 00 
	condition:
		any of ($a_*)
 
}