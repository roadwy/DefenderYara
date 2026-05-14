
rule Trojan_BAT_Injector_SX_MTB{
	meta:
		description = "Trojan:BAT/Injector.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,5f 00 5f 00 08 00 00 "
		
	strings :
		$a_80_0 = {3d 20 47 65 74 2d 50 72 6f 63 65 73 73 20 2d 4e 61 6d 65 20 28 22 72 65 72 6f 6c 70 78 65 22 5b 2d 31 2e 2e 2d 38 5d 20 2d 6a 6f 69 6e 20 22 22 29 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //= Get-Process -Name ("rerolpxe"[-1..-8] -join "") -ErrorAction SilentlyContinue  30
		$a_80_1 = {24 53 48 4f 55 4c 44 45 52 45 6c 65 63 74 69 6f 6e 2c 20 24 53 48 4f 55 4c 44 45 52 45 6c 65 63 74 69 6f 6e 2e 4c 65 6e 67 74 68 2c } //$SHOULDERElection, $SHOULDERElection.Length,  20
		$a_80_2 = {24 53 48 4f 55 4c 44 45 52 45 6c 65 63 74 69 6f 6e 20 3d 20 24 63 6f 6d 62 69 6e 65 64 44 61 74 61 } //$SHOULDERElection = $combinedData  20
		$a_80_3 = {24 6d 75 74 65 78 20 3d 20 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 2e 4d 75 74 65 78 28 24 66 61 6c 73 65 2c 20 24 6d 75 74 65 78 4e 61 6d 65 29 } //$mutex = New-Object System.Threading.Mutex($false, $mutexName)  15
		$a_80_4 = {24 72 65 73 75 6c 74 20 3d 20 5b 57 69 6e 41 50 49 5d 3a 3a 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 28 24 68 50 72 6f 63 65 73 73 2c 20 24 61 6c 6c 6f 63 41 64 64 72 2c 20 24 53 48 4f 55 4c 44 45 52 45 6c 65 63 74 69 6f 6e 2c 20 24 53 48 4f 55 4c 44 45 52 45 6c 65 63 74 69 6f 6e 2e 4c 65 6e 67 74 68 } //$result = [WinAPI]::WriteProcessMemory($hProcess, $allocAddr, $SHOULDERElection, $SHOULDERElection.Length  8
		$a_80_5 = {24 65 78 70 50 72 6f 63 20 3d 20 47 65 74 2d 50 72 6f 63 65 73 73 20 2d 49 64 20 24 4f 31 4d 64 56 59 49 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //$expProc = Get-Process -Id $O1MdVYI -ErrorAction SilentlyContinue  2
		$a_80_6 = {52 65 2d 69 6e 6a 65 63 74 20 69 6e 74 6f 20 6e 65 77 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 70 72 6f 63 65 73 73 } //Re-inject into new explorer.exe process  8
		$a_80_7 = {43 72 65 61 74 65 20 72 65 6d 6f 74 65 20 74 68 72 65 61 64 20 74 6f 20 65 78 65 63 75 74 65 20 73 68 65 6c 6c 63 6f 64 65 } //Create remote thread to execute shellcode  2
	condition:
		((#a_80_0  & 1)*30+(#a_80_1  & 1)*20+(#a_80_2  & 1)*20+(#a_80_3  & 1)*15+(#a_80_4  & 1)*8+(#a_80_5  & 1)*2+(#a_80_6  & 1)*8+(#a_80_7  & 1)*2) >=95
 
}