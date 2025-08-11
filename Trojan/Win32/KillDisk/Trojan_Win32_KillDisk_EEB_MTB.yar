
rule Trojan_Win32_KillDisk_EEB_MTB{
	meta:
		description = "Trojan:Win32/KillDisk.EEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {22 d0 88 94 05 ?? ?? ?? ?? 40 3d 80 a9 03 00 72 ?? ?? ?? ?? ?? ?? ?? c7 85 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}