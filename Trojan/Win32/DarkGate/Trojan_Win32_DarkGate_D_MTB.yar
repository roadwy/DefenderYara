
rule Trojan_Win32_DarkGate_D_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 99 f7 fd 83 6c ?? ?? ?? 8b c2 99 f7 ff 8b 7c ?? ?? 31 01 8b 44 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}