
rule TrojanSpy_Win64_RustyStealer_C{
	meta:
		description = "TrojanSpy:Win64/RustyStealer.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 6c 75 63 61 6b 5c 44 65 73 6b 74 6f 70 5c 72 75 73 74 2d 63 32 5c 63 6c 69 65 6e 74 5c 6c 69 62 73 5c 6d 65 6d 65 78 65 63 5c 73 72 63 5c 70 65 70 61 72 73 65 72 5c 70 65 2e 72 73 } //1 C:\Users\lucak\Desktop\rust-c2\client\libs\memexec\src\peparser\pe.rs
	condition:
		((#a_01_0  & 1)*1) >=1
 
}