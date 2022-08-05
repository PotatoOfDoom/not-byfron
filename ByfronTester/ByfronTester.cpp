#include <iostream>
#include <Windows.h>

int main()
{
	LoadLibrary(L"not-byfron.dll");
	std::cout << "AyyLmao" << std::endl;
}
