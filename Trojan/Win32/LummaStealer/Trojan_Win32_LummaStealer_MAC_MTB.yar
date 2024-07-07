
rule Trojan_Win32_LummaStealer_MAC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a1 bc 50 44 00 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 bc 50 44 00 8a 0d be 50 44 00 30 0c 33 83 ff 0f 75 39 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}