
rule Trojan_Win32_StrelaStealer_PC_MTB{
	meta:
		description = "Trojan:Win32/StrelaStealer.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 89 df 41 81 f7 ?? ?? ?? ?? 45 89 cc 41 81 e4 ?? ?? ?? ?? 45 21 fe 41 89 fd 41 81 e5 ?? ?? ?? ?? 45 21 fb 45 09 f4 45 09 dd 45 31 ec 41 09 f9 41 83 f1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}