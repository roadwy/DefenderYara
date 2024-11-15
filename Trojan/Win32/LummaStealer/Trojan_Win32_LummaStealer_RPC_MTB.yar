
rule Trojan_Win32_LummaStealer_RPC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_03_0 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 31 } //1
		$a_03_1 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 31 2e 50 72 69 6e 74 2e 66 75 6e 63 31 } //100
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}