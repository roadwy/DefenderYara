
rule Trojan_Win32_ScriptExec_A{
	meta:
		description = "Trojan:Win32/ScriptExec.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {6d 73 68 74 61 2e 65 78 65 } //mshta.exe  1
		$a_80_1 = {57 73 63 72 69 70 74 2e 53 68 65 6c 6c } //Wscript.Shell  1
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 43 6f 6d 6d 61 6e 64 20 57 72 69 74 65 2d 48 6f 73 74 20 41 74 74 61 63 6b 49 51 } //powershell.exe -nop -Command Write-Host AttackIQ  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}