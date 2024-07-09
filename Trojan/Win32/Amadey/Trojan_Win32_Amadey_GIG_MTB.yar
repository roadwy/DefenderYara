
rule Trojan_Win32_Amadey_GIG_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 d7 e8 59 81 44 24 ?? 8d 8e b1 2f b8 ?? ?? ?? ?? f7 64 24 ?? 8b 44 24 ?? 81 6c 24 ?? 59 dd a3 59 b8 ?? ?? ?? ?? f7 64 24 ?? 8b 44 24 ?? 81 6c 24 ?? 74 b0 32 20 81 6c 24 ?? ec 47 b6 15 81 44 24 ?? 76 74 dd 1e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}