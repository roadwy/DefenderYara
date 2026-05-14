
rule Trojan_Win32_MuddyWaterz_A_MTB{
	meta:
		description = "Trojan:Win32/MuddyWaterz.A!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 00 61 00 74 00 61 00 3a 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3b 00 62 00 61 00 73 00 65 00 36 00 34 00 2c 00 } //1 data:application/javascript;base64,
		$a_00_1 = {64 00 65 00 6e 00 6f 00 2e 00 65 00 78 00 65 00 } //1 deno.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}