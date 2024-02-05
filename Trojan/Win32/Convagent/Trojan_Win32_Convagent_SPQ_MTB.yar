
rule Trojan_Win32_Convagent_SPQ_MTB{
	meta:
		description = "Trojan:Win32/Convagent.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {89 44 8f e4 8b 44 8e e8 89 44 8f e8 8b 44 8e ec 89 44 8f ec 8b 44 8e f0 89 44 8f f0 8b 44 8e f4 89 44 8f f4 8b 44 8e f8 89 44 8f f8 8b 44 8e fc 89 44 8f fc 8d 04 8d 00 00 00 00 03 f0 03 f8 ff 24 95 a0 c8 55 00 } //02 00 
		$a_01_1 = {6d 6f 79 75 6e 2f 44 61 74 61 2f 45 53 50 5f 4e 47 2e 64 61 74 50 4b } //00 00 
	condition:
		any of ($a_*)
 
}